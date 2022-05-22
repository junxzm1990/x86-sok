import numpy as np
from fairseq.models.roberta import RobertaModel

import sys

def compare(starts_label, starts_pred, nop_label):
    tp = fp = fn = 0
    gt_lables = set(starts_label)
    pred_sets = set(starts_pred)

    for st in starts_pred:
        if st in gt_lables:
            tp += 1
        elif fp not in nop_label:
            fp += 1

    for st in starts_label:
        if st not in pred_sets:
            fn += 1

    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1 = 2 * precision * recall / (precision + recall)

    print("Precision is %f" % precision)
    print("Recall is %f" % recall)
    print("F1 score is %f" % f1)

def predict(filename, model):
    f_truth = open(filename, 'r')

    starts_label = []
    starts_pred = []
    nop_label = []

    tokens = []
    for i, line_truth in enumerate(f_truth):
        line_truth_split = line_truth.strip().split()
        tokens.append(line_truth_split[0].lower())
        if len(line_truth_split) > 1:
            if line_truth_split[1] == 'S':
                starts_label.append(i)
            elif line_truth_split[1] == '-':
                nop_label.append(i)

    f_truth.close()
    batch_size = 512
    for i_block in range(0, len(tokens), batch_size):
        if i_block + batch_size > len(tokens):
            continue
        else:
            to_encode_tokens = tokens[i_block:i_block + batch_size]

        encoded_tokens = model.encode(' '.join(to_encode_tokens))
        logprobs = model.predict('funcbound', encoded_tokens[:batch_size])
        labels = logprobs.argmax(dim=2).view(-1).data

        for i_token, label in enumerate(labels):
            if label == 1:
                starts_pred.append(i_block + i_token)

    return starts_label, starts_pred, nop_label

def main():
    if len(sys.argv) < 4:
        print("python3 %s <model.pt> <test> <data-bin>" % (sys.argv[0]))
        exit(-1)

    roberta = RobertaModel.from_pretrained(sys.argv[1], 'checkpoint_best.pt',
                            sys.argv[3], bpe = None, user_dir='finetune_tasks')
    roberta.eval()

    starts_label, starts_pred, nop_label = predict(sys.argv[2], roberta)

    compare(starts_label, starts_pred, nop_label)

if __name__ == '__main__':
    main()
