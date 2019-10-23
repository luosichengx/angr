import json
import re
with open("../data/lib_60s.txt",'r') as f:
    a = f.read()

s = re.findall("[0-9]+ path", a)
s = [x[:-5] for x in s]
n = sum(list(map(int, s)))
print(n)
# a = a[:10]
# jsondata = json.dumps(a, indent=4, separators=(',', ': '))
# with open('record.txt', 'a') as f:
#     f.write(jsondata + ",\n")