import nvdlib
r = nvdlib.searchCVE(cveId='CVE-2024-24855')[0]
print(r.v31severity + ' - ' + str(r.v31score))
print(r.descriptions[0].value)
