import sys
import pandas
import matplotlib.pyplot as plt
import seaborn as sns
# from brokenaxes import brokenaxes

def draw(csv, output):
    plt.figure(figsize=(10.3,6.5))
    scores = pandas.read_csv(csv)
    print(scores.columns)
    ax = sns.violinplot(x="OPT", y = "F1 Score", hue = "GT", data = scores, bw = 1.0,
                    palette="pastel", split = False, cut = 0, order = ["O0", "O2", "O3", "Os", "Of"], hue_order = ["Precision"])
    ax.legend_.set_title(None)
    leg = plt.gca().get_legend()
    ltext = leg.get_texts()
    plt.setp(ltext, fontsize=12, fontweight='bold', fontname="Times New Roman")
    plt.xticks(fontsize=14, fontweight='bold', fontname="Times New Roman")
    plt.yticks(fontsize=13, fontweight='bold', fontname="Times New Roman")
    plt.xlabel("Optimization Level", fontsize=14, fontweight="heavy", fontname="Times New Roman")
    plt.ylabel("", fontsize=14, fontweight="heavy", fontname="Times New Roman")
    plt.ylim(80.0, 100.01)
    leg.remove()
    print('save %s' % output)
    plt.savefig(output)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Please give the csv data")
        exit(-1)

    draw(sys.argv[1], sys.argv[2])
