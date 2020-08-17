'''
environment: windows10, visual studio 15, python3
'''
import refInf_pb2
import optparse
import logging
import os
import sys
import subprocess

logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level = logging.DEBUG)


def parse_fixup(pdb_file, bin_path, output):
    
    tmp_file = './tmp_cvdump.fixup'
    
    with open(tmp_file, 'w+') as fout:
        ret_status = subprocess.call("dumpbin -HEADERS %s" % bin_path, stdout=fout, shell = True)
        if ret_status:
            logging.error("dump symbols of binary")
            exit(-1)
    fout.close()

    image_base = 0x0
    find_base = False
    with open(tmp_file, 'r+') as fout:
        for line in fout.readlines():
            if 'image base' in line:
                split_line = line.strip().split()
                image_base = int(split_line[0], 16)
                logging.debug("Image base is 0x%lx", image_base)
                find_base = True
                break
    fout.close()
    if not find_base:
        logging.error("Can't parse the image base correctly!")
        exit(-1)
                

    ret_status = subprocess.call('cvdump -?', stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=True)
    if ret_status < 0:
        logging.error("Can't find cvdump executable. please install cvdump firstly!")
        exit(-1)
    
    with open(tmp_file, 'w+') as fout:
        ret_status = subprocess.call('cvdump -fixup %s' % pdb_file, stdout=fout, stderr=sys.stderr, shell = True)
        if ret_status < 0:
            logging.error("cvdump -fixup error!")
            exit(-1)
        
        fout.close()
    
    ref_inf = refInf_pb2.RefList()

    triger = False
    with open(tmp_file, 'r+') as fout:

        for line in fout.readlines():
            
            line = line.strip()
            if not triger:
                if '-------' in line:
                    triger = True
                    continue
            
            if triger:

                ref = ref_inf.ref.add()

                cur_list = line.split()

                ref_type = int(cur_list[0], 16)
                ref_rva = int(cur_list[2], 16)
                ref_target = int(cur_list[3], 16)

                ref.ref_va = image_base + ref_rva
                ref.target_va = image_base + ref_target

                # ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
                if ref_type == 1:
                    ref.ref_size = 8
                elif ref_type == 0xa:
                    ref.ref_size = 2
                elif ref_type == 0xc:
                    ref.ref_size = 1
                else:
                    ref.ref_size = 4

                logging.debug("current fixup: 0x%lx -> 0x%lx" % (ref.ref_va, ref.target_va))

                # TODO. add support of fixup type(d2d, d2c, c2c, c2d)
    fout.close()

    with open(output, 'wb') as output_file:
        output_file.write(ref_inf.SerializeToString())

    os.system('rm %s' % tmp_file)



if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "./tmp_ref.pb") 
    parser.add_option("-p", "--pdb", dest = "pdb", action = "store", type = "string", \
            help = "pdb(program database)", default = None)
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary path", default = None)
   

    (options, args) = parser.parse_args()

    if options.pdb == None:
        logging.error("Please input pdb file(with -p)!")
        exit(-1)

    if options.binary == None:
        logging.error("Please input binary file(with -b)!")
        exit(-1)
    
    parse_fixup(options.pdb, options.binary, options.output)
        