

def get_stats(file):
    tp = tn = fp = fn = 0
    err = 0
    curr_cve = ""
    res = ""
    first = True
    old_cve = set()
    with open(file, "r") as f:
        for line in f:
            if "---" in line or "CVE-ID" in line: continue
            cve = line.split("|")[0]
            if cve != curr_cve:
                if cve in old_cve: print(cve)
                else: old_cve.add(cve)
                curr_cve = cve
                if not first:
                    if res == "TP":
                        tp += 1
                    elif res == "TN":
                        tn += 1
                    elif res == "FN":
                        fn += 1
                    elif res == "FP":
                        fp += 1
                    else:
                        err += 1
                else:
                    first = False
            if "TP" in line:
                res = "TP"
            elif "TN" in line:
                res = "TN"
            elif "FN" in line:
                res = "FN"
            elif "FP" in line:
                res = "FP"
            else:
                res = "ERR"
        if res == "TP":
            tp += 1
        elif res == "TN":
            tn += 1
        elif res == "FN":
            fn += 1
        elif res == "FP":
            fp += 1
        else:
            err += 1

    print("\n"+"#"*21)
    print(f"#\tTP: {tp}\t    #\n#\tTN: {tn}\t    #\n#\tFP: {fp}\t    #\n#\tFN: {fn}\t    #")
    print("#"*21+"\n")
    print(f"####  TOTAL: {tp+fp+tn+fn+err} ({err} don't run) ####")
    print(len(old_cve))

if __name__ == "__main__":
    get_stats("../docker-agent/results.txt")