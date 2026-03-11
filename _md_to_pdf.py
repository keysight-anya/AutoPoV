from pathlib import Path
import re
import textwrap

SRC = Path('/home/user/AutoPoV/DOCS_APPLICATION_FLOW.md')
DST = Path('/home/user/AutoPoV/DOCS_APPLICATION_FLOW.pdf')

text = SRC.read_text(encoding='utf-8')
lines = text.splitlines()

out_lines = []
in_code = False
code_fence = chr(96) * 3
for line in lines:
    if line.strip().startswith(code_fence):
        in_code = not in_code
        continue
    if in_code:
        out_lines.append(line)
        continue
    if line.startswith('#'):
        title = line.lstrip('#').strip()
        if title:
            out_lines.append(title.upper())
            out_lines.append('')
        continue
    line = re.sub(r'^\s*[-*]\s+', '- ', line)
    line = re.sub(r'^\s*\d+\.\s+', '- ', line)
    line = line.replace('', '')
    out_lines.append(line)

wrapped = []
for line in out_lines:
    if line.strip() == '':
        wrapped.append('')
        continue
    if line.startswith('    ') or line.startswith('\t'):
        wrapped.append(line)
        continue
    for w in textwrap.wrap(line, width=90):
        wrapped.append(w)

PAGE_W = 612
PAGE_H = 792
MARGIN = 72
LINE_H = 14
LINES_PER_PAGE = int((PAGE_H - 2 * MARGIN) / LINE_H)

pages = [wrapped[i:i + LINES_PER_PAGE] for i in range(0, len(wrapped), LINES_PER_PAGE)]

objects = []

def add(obj_str: str) -> int:
    objects.append(obj_str)
    return len(objects)

font_obj = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')

page_objs = []
content_objs = []
for page_lines in pages:
    content = ['BT', '/F1 12 Tf', f'{MARGIN} {PAGE_H - MARGIN} Td', f'{LINE_H} TL']
    for line in page_lines:
        if line == '':
            content.append('T*')
        else:
            esc = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            content.append(f'({esc}) Tj')
            content.append('T*')
    content.append('ET')
    stream = '\n'.join(content)
    content_obj = add(f'<< /Length {len(stream.encode(\'utf-8\'))} >>\nstream\n{stream}\nendstream')
    content_objs.append(content_obj)

pages_obj_index = len(objects) + 1

for content_obj in content_objs:
    page_obj = add(
        '<< /Type /Page /Parent {pages} 0 R /Resources << /Font << /F1 {font} 0 R >> >> '
        '/MediaBox [0 0 {w} {h}] /Contents {content} 0 R >>'.format(
            pages=pages_obj_index,
            font=font_obj,
            w=PAGE_W,
            h=PAGE_H,
            content=content_obj,
        )
    )
    page_objs.append(page_obj)

kids = ' '.join(f'{p} 0 R' for p in page_objs)
add(f'<< /Type /Pages /Kids [{kids}] /Count {len(page_objs)} >>')

catalog_obj = add('<< /Type /Catalog /Pages {pages} 0 R >>'.format(pages=pages_obj_index))

xref_positions = []
with DST.open('wb') as f:
    f.write(b'%PDF-1.4\n')
    for i, obj in enumerate(objects, start=1):
        xref_positions.append(f.tell())
        f.write(f'{i} 0 obj\n'.encode('utf-8'))
        f.write(obj.encode('utf-8'))
        f.write(b'\nendobj\n')
    xref_start = f.tell()
    f.write(f'xref\n0 {len(objects) + 1}\n'.encode('utf-8'))
    f.write(b'0000000000 65535 f \n')
    for pos in xref_positions:
        f.write(f'{pos:010d} 00000 n \n'.encode('utf-8'))
    f.write(b'trailer\n')
    f.write(f'<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\n'.encode('utf-8'))
    f.write(b'startxref\n')
    f.write(f'{xref_start}\n'.encode('utf-8'))
    f.write(b'%%EOF\n')

print(f'Wrote {DST}')
