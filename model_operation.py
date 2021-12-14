import os


def file_operation(doc_path):
    """
    文件读取
    """
    for root, dirs, files in os.walk(doc_path):
        for name in files:
            if name.endswith('.h'):
                name = name.replace('.h', '')
                o_path = os.path.join(root, '{}.h'.format(name))
                r_path = os.path.join(root, 'result/{}.h'.format(name))
                file_exe(o_path, r_path)


def file_exe(o_path, r_path):
    """
    文件操作
    """
    props = []
    key = ''
    props_map = {}
    with open(r_path, 'a') as f1:
        with open(o_path, 'r') as f:
            for line in f.readlines():
                if line.startswith('@interface'):
                    key = line.split('@interface')[1].split(':')[0].strip()
                if line.startswith('@property'):
                    if 'readonly' not in line:
                        line = line.replace('nonatomic', 'readonly, nonatomic')
                    prop = line.split(')')[-1].split(';')[0].strip()
                    props.append(prop)
                if '@end' in line:
                    if len(key) > 0:
                        props_map[key] = props
                    props = []
                f1.write(line)
    with open(r_path.replace('.h', '.m'), 'a') as f1:
        with open(o_path.replace('.h', '.m'), 'r') as f:
            for line in f.readlines():
                f1.write(line)
                if line.startswith('@implementation'):
                    key = line.split('@implementation')[-1].strip().replace('\n', '')
                    f1.write('{\n')
                    props = props_map[key]
                    mp = []
                    for prop in props:
                        if '*' in prop:
                            pps = prop.split('*')
                            t = pps[0].strip()
                            v = pps[1].strip()
                            f1.write('{} *_{};\n'.format(t, v))
                            kk = '-({} *){}'.format(t, v)
                            vv = 'return _{}'.format(v)
                            mp.append(kk + '{' + vv + ';}\n')
                        else:
                            pps = prop.split(' ')
                            t = pps[0].strip()
                            v = pps[1].strip()
                            f1.write('{} _{};\n'.format(t, v))
                            kk = '-({}){}'.format(t, v)
                            vv = 'return _{}'.format(v)
                            mp.append(kk + '{' + vv + ';}\n')
                    f1.write('}\n')
                    for m in mp:
                        f1.write(m)


if __name__ == '__main__':
    doc_path = '/Users/xxx/Desktop/'
    file_operation(doc_path)
    pass

