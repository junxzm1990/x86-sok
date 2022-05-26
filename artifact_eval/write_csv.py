import sys
import os

def write_csv(input, output, gt):
    scores = list()
    opts = list()
    with open(input, 'r+') as r_f:
        content = r_f.read()
        lines = content.strip().split("\n")
        for line in lines:
            if line == "":
                continue
            try:
                f1_score = float(line.strip().split(' ')[-1]) * 100
            except:
                continue
            scores.append(f1_score)
            if "_O0" in line:
                opts.append("O0")
            elif "_O2" in line:
                opts.append("O2")
            elif "_O3" in line:
                opts.append("O3")
            elif "_Os" in line:
                opts.append("Os")
            elif "_Of" in line:
                opts.append("Of")
    w_content = ""
    if not os.path.exists(output):
        w_content = "OPT,GT,F1 Score\n"
    for (i, score) in enumerate(scores):
        w_content += ("%s,%s,%f\n" % (opts[i], gt_name, score))

    with open(output, 'a+') as w_f:
        w_f.write(w_content)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Please input the arguments: python3 write_csv.py <input> <output> <gt name>")
        exit(-1)


    input = sys.argv[1]
    output = sys.argv[2]
    gt_name = sys.argv[3]

    write_csv(input, output, gt_name)
