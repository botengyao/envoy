import os, re, sys
ROOTS = sys.argv[1].split(':')
seen, order = set(), []
def find(rel):
    for r in ROOTS:
        p = os.path.join(r, rel)
        if os.path.isfile(p):
            return p
    return None
def walk(rel):
    if rel in seen:
        return
    seen.add(rel)
    p = find(rel)
    if p is None:
        return  # well-known types shipped with protoc
    for m in re.finditer(r'^import\s+(?:public\s+)?"([^"]+)"', open(p).read(), re.M):
        walk(m.group(1))
    order.append(rel)
for t in sys.argv[2:]:
    walk(t)
print('\n'.join(order))
