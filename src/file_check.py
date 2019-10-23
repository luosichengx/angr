import json

with open("../data/nolib_60s.json",'r') as f:
    jsondata = f.read()
a = json.loads(jsondata)
print(len(a))
s = []
c = 0
for i in a:
    if i["file name"] not in s:
        s.append(i["file name"])
        s.append(i)
        c += 1
print(c)
# a = a[:10]
# jsondata = json.dumps(a, indent=4, separators=(',', ': '))
# with open('record.txt', 'a') as f:
#     f.write(jsondata + ",\n")