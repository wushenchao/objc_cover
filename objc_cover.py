#!/usr/bin/python
"""
代码中未被使用的类和方法检测

python2: https://github.com/nst/objc_cover

1、cmp 函数
https://www.runoob.com/python/func-number-cmp.html

2、AttributeError: '_io.TextIOWrapper' object has no attribute 'xreadlines'
https://blog.csdn.net/kicilove/article/details/78433844

3、can't find implemented methods
https://cloud.tencent.com/developer/article/1857943

4、TypeError: sort() takes no positional arguments
"""
__author__ = "Nicolas Seriot"
__date__ = "2010-03-01"
__license__ = "GPL"

import os
import re
import shutil
import sys
import tempfile
import operator
from functools import cmp_to_key

def verified_macho_path(args):
    if len(sys.argv) != 2:
        return None
    
    path = sys.argv[1]
    
    if not os.path.isfile(path):
        return None
    
    # Apparently there is a bug in otool -- it doesn't seem to like executables
    # with spaces in the names. If this is the case, make a copy and analyze that.
    if ' ' in os.path.basename(path):
        # don't remove the spaces, that could lead to an empty string
        new_filename = path.replace(' ', '_')
        new_path = os.path.join(tempfile.mkdtemp(), new_filename)
        shutil.copy(path, new_path)
        path = new_path
    
    cmd = "/usr/bin/file -b %r" % path
    s = os.popen(cmd).read()
    
    if not s.startswith('Mach-O'):
        return None
    
    return path


def signature_cmp(m1, m2):
    """
    1、cmp 函数替换
    """
    cls1 = m1[2:].split(' ')[0]
    cls2 = m2[2:].split(' ')[0]
    
    result = operator.eq(cls1, cls2)
    
    if result:  # same class
        if m1.startswith('+') and m2.startswith('-'):
            return -1
        elif m1.startswith('-') and m2.startswith('+'):
            return +1
        else:  # same sign
            if operator.eq(m1, m2):  # m1 = m2
                return 0
            elif operator.lt(m1, m2):  # m1 < m2
                return -1
            return 1
    
    return result


def implemented_methods(path):
    """
    获取项目中所有方法
    returns {'sel1':[sig1, sig2], 'sel2':[sig3]}
    """
    re_sig_sel_ios = re.compile("\s*imp\s*0x\w+ ([+|-]\[.+\s(.+)\])")

    re_sig_sel_mac = re.compile("\s*imp ([+|-]\[.+\s(.+)\])")

    impl = {}  # sel -> clsmtd
    
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()
    for line in lines:
        results = re_sig_sel_ios.findall(line)
        if not results:
            results = re_sig_sel_mac.findall(line)
        # print(results)
        
        if not results or len(results) == 0:
            continue
        # print(results)
        (sig, sel) = results[0]
        
        if sel in impl:
            impl[sel].append(sig)
        else:
            impl[sel] = [sig]
    
    return impl


def referenced_selectors(path):
    """
    获取项目中被引用的方法
    """
    re_sel = re.compile("__TEXT:__objc_methname:(.+)")
    
    refs = set()
    
    lines = os.popen("/usr/bin/otool -v -s __DATA __objc_selrefs %s" % path).readlines()  # ios & mac
    # print(lines)
    for line in lines:
        results = re_sel.findall(line)
        if results:
            refs.add(results[0])
    
    return refs


def potentially_unreferenced_methods():
    """
    获取未使用的方法
    """
    implemented = implemented_methods(path)
    
    if not implemented:
        print("# can't find implemented methods")
        sys.exit(1)
    
    referenced = referenced_selectors(path)
    # print(referenced)
    l = []

    # print "-- implemented:", len(implemented)
    # print "-- referenced:", len(referenced)
    
    for sel in implemented:
        if sel not in referenced:
            for method in implemented[sel]:
                l.append(method)

    # l.sort(signature_cmp)
    l.sort(key=cmp_to_key(signature_cmp))
    
    return l


def potentially_all_classes():
    """
    获取项目中所有类名称
    """
    re_sel = re.compile("(\w{16})\s\s([A-Za-z].+)")
    
    refs = set()
    
    lines = os.popen("/usr/bin/otool -v -s __TEXT __objc_classname %s" % path).readlines()
    for line in lines:
        results = re_sel.findall(line)
        if results:
            (address, symbol) = results[0]
            refs.add(symbol)
    return refs


def potentially_unreferenced_classes():
    """
    获取未使用类地址
    """
    # 获取引用类
    re_class_refs = re.compile(".+__objc_classrefs.*")
    # 获取类名
    re_sel = re.compile("(\w{16}) .* _OBJC_CLASS_\$_(.+)")
    
    class_refs = False
    
    all_refs = potentially_all_classes()
    refs = set()
    
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()  # ios & mac
    for line in lines:
        if class_refs:  # 获取引用类
            result = re_sel.findall(line)
            if result and len(result) > 0:
                (address, symbol) = result[0]
                refs.add(symbol)
        else:
            results = re_class_refs.findall(line)
            if results and len(results) > 0:
                class_refs = True
    # print(all_refs - refs)
    return all_refs - refs


def potentially_unreferenced_classes1():
    """
    获取未使用类地址
    """
    # 获取所有类
    re_class_list = re.compile(".+__objc_classlist.*")
    # 获取引用类
    re_class_refs = re.compile(".+__objc_classrefs.*")
    # 提取类名
    re_sel = re.compile("(\w{16}) .* _OBJC_CLASS_\$_(.+)")
    
    start_class_list = False
    start_class_refs = False

    all_refs = set()
    refs = set()

    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()
    for line in lines:
        if start_class_refs:  # 获取引用类
            result = re_sel.findall(line)
            if result and len(result) > 0:
                (address, symbol) = result[0]
                refs.add(symbol)
        else:
            results = re_class_refs.findall(line)
            if results and len(results) > 0:
                start_class_refs = True
                continue
            if start_class_list:  # 获取所有类
                result = re_sel.findall(line)
                if result and len(result) > 0:
                    (address, symbol) = result[0]
                    all_refs.add(symbol)
            else:
                results = re_class_list.findall(line)
                if results and len(results) > 0:
                    start_class_list = True
    # print(all_refs - refs)
    return all_refs - refs


if __name__ == "__main__":
    if not path:
        print("Usage: %s MACH_O_FILE" % sys.argv[0])
        sys.exit(1)

    print("# the following classes may be unreferenced")
    # classes = potentially_unreferenced_classes()
    classes = potentially_unreferenced_classes1()
    for cls in classes:
        if cls.startswith('JDG') or cls.startswith('JBG'):
           print(cls)
    
    print("# the following methods may be unreferenced")
    methods = potentially_unreferenced_methods()
    for m in methods:
        if (m.startswith('-[JDG') or m.startswith('+[JDG')) and 'cxx_destruct' not in m and 'collectionView:' not in m:
            print(m)

