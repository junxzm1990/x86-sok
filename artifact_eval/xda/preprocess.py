import optparse
import os
from py import process

from requests import options

def serialize_output(trainlist, output, validy, input):
    trainning_list = list()

    with open(trainlist, 'r+') as tr:
        [trainning_list.append(line.strip()) for line in tr]

    data_output = open("%s.data" % output, 'w')
    label_output = open("%s.label" % output, 'w')
    processing_list = list()
    for root, _, files in os.walk(input):
        for filename in files:
            full_path = os.path.join(root, filename)
            if not validy and filename in trainning_list:
                processing_list.append(full_path)
            elif validy and filename not in trainning_list:
                processing_list.append(full_path)

    current_buf = ""
    current_label_buf = ""
    current_index = 0
    for f_path in processing_list:
        with open(f_path, "r+") as f:
            print(f_path)
            for line in f:
                data = line.split(" ")[0]
                label = line.split(" ")[1].strip()
                data_int = int(data, 16)
                current_buf += (" %02x" % data_int)
                current_label_buf += (" %s" % label)
                current_index += 1
                if current_index == 512:
                    current_buf += "\n"
                    current_label_buf += "\n"
                    data_output.write(current_buf.lstrip())
                    label_output.write(current_label_buf.lstrip())
                    current_buf = ""
                    current_label_buf = ""
                    current_index = 0

    data_output.close()
    label_output.close()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-t", "--trainlist", dest = "trainlist", action = "store",
        type = "string", help = "train list", default = None)
    parser.add_option("-i", "--input", dest = "input", action = "store",
        type = "string", help = "input", default = None)
    parser.add_option("-o", "--output", dest = "output", action = "store",
        type = "string", help = "output file", default = None)
    parser.add_option("-v", "--validy", dest = "validy", action = "store_true", \
        default = False, help = "validy test")

    (options, args) = parser.parse_args()

    if options.trainlist == None:
        print("Please input the ground truth list")
        exit(-1)

    if options.output == None:
        print("Please input the output path")
        exit(-1)

    serialize_output(options.trainlist, options.output, options.validy, options.input)
