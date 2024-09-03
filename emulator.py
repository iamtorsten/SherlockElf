# Android Emulator for static analysis of ELF binaries

import logging
import posixpath
import os.path
import sys

from emu.memu                   import Memu
from emu.utils                  import memory_helpers
from emu.java.java_class_def    import JavaClassDef
from emu.java.java_method_def   import java_method_def
from emu.java.classes.string    import String
from emu.java.classes.list      import List


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

class ms_bd_c_k(metaclass=JavaClassDef, jvm_name='ms/bd/o/k'):
    @staticmethod
    @java_method_def(name='b', args_list=["jint", "jint", "jlong", "jstring", "jobject"],
                     signature='(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def b(emu, i1, i2, l, s, obj):
        if i1 == 65539:
            return String("/data/user/0/com.zhiliaoapp.musically/files/.msdata")
        elif i1 == 16777233:
            return String("23.3.4")
        elif i1 == 33554433:
            return True
        elif i1 == 33554434:
            return True


class ms_bd_c_a0(metaclass=JavaClassDef, jvm_name='ms/bd/o/a0', jvm_super=ms_bd_c_k):
    pass


class MS(metaclass=JavaClassDef, jvm_name='com/bytedance/mobsec/metasec/ov/MS', jvm_super=ms_bd_c_a0):
    @staticmethod
    @java_method_def(name='a', signature='()V', native=False)
    def a(emu):
        pass


class java_lang_Thread(metaclass=JavaClassDef, jvm_name='java/lang/Thread'):
    @java_method_def(name="currentThread", signature='()Ljava/lang/Thread;', native=False)
    def currentThread(self):
        return java_lang_Thread()

    @java_method_def(name="getStackTrace", signature='()[Ljava/lang/StackTraceElement;', native=False)
    def getStackTrace(self, s):
        return List([])


def get_sign(s1, s2):
    g_vfs_path = "%s/vfs" % os.path.dirname(os.path.abspath(__file__))
    emulator = Memu(
        vfs_root=posixpath.join(posixpath.dirname(__file__), g_vfs_path),
        muti_task=True
    )
    vfs_path = emulator.get_vfs_root()
    libcm = emulator.load_library("%s/system/lib/libc.so" % vfs_path)
    libml = emulator.load_library(
        "%s/data/data/com.zhiliaoapp.musically/libmetasec_ov.so" % vfs_path, do_init=False)
    emulator.java_classloader.add_class(ms_bd_c_k)
    emulator.java_classloader.add_class(ms_bd_c_a0)
    emulator.java_classloader.add_class(MS)
    emulator.java_classloader.add_class(java_lang_Thread)
    emulator.call_symbol(libml, 'JNI_OnLoad',
                         emulator.java_vm.address_ptr, 0x00)
    s1_addr = emulator.call_symbol(libcm, 'malloc', len(s1)+1)
    s2_addr = emulator.call_symbol(libcm, 'malloc', len(s2)+1)
    memory_helpers.write_utf8(emulator.mu, s1_addr, s1)
    memory_helpers.write_utf8(emulator.mu, s2_addr, s2)

    result_addr = emulator.call_native(libml.base + 0x51280 + 1, s1_addr, s2_addr)
    result = memory_helpers.read_utf8(emulator.mu, result_addr)
    return result

import json

s1 = "https://ichannel.snssdk.com/service/2/app_alert_check/?ac=wifi&channel=shenmasem_ls_dy_210&aid=1128&app_name=aweme&version_code=230300&version_name=23.3.0&device_platform=android&os=android&ssmix=a&device_type=Pixel&device_brand=google&language=zh&os_api=27&os_version=8.1.0&openudid=b104cd40fd2b3224&manifest_version_code=230301&resolution=1080*1794&dpi=420&update_version_code=23309900&_rticket=1670126182805&package=com.zhiliaoapp.musically&cpu_support64=true&host_abi=armeabi-v7a&is_guest_mode=0&app_type=normal&minor_status=0&appTheme=light&need_personal_recommend=1&is_android_pad=0&ts=1670126133&cdid=26ed513b-3f69-440f-ba7d-4b53f333e88c&md=0&iid=4072246474186391&device_id=3122268427780248&uuid=352531081299354"
s2 = "x-ss-req-ticket\r\n"\
    "1656193928088\r\n"\
    "personal-recommend-status\r\n"\
    "1\r\n"\
    "x-vc-bdturing-sdk-version\r\n"\
    "2.2.1.cn\r\n"\
    "passport-sdk-version\r\n"\
    "30626\r\n"\
    "sdk-version\r\n"\
    "2\r\n"\
    "x-tt-trace-id\r\n"\
    "00-48cde91e0100ba02e9a49302ff57211e-48cde91e0100ba02-01\r\n"\
    "user-agent\r\n"\
    "com.zhiliaoapp.musically/230300 (Linux; U; Android 8.1.0; zh_CN; Pixel; Build/OPM1.171019.014;tt-ok/3.12.13.1)\r\n"\
    "accept-encoding\r\n"\
    "gzip, deflate"
sign = get_sign(s1, s2)
print(sign)
