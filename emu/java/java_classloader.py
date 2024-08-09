from .java_class_def import JavaClassDef
from .classes.clazz import Class

class JavaClassLoader(metaclass=JavaClassDef, jvm_name='java/lang/ClassLoader'):

    """
    :type class_by_id dict[int, JavaClassDef]
    :type class_by_name dict[string, JavaClassDef]
    """
    def __init__(self):
        self.class_by_id = dict()
        self.class_by_name = dict()
    #

    def add_class(self, clazz):
        if not isinstance(clazz, JavaClassDef):
            raise ValueError('Expected a JavaClassDef.')
        #
        if clazz.jvm_name in self.class_by_name:
            raise KeyError('The class \'%s\' is already registered.' % clazz.jvm_name)
        #
        if (clazz.class_object == None):
            #FIXME 两个emulaotr add_class是同一个class 实例,会互相影响
            clazz.class_object = Class(clazz, self)
        #
        self.class_by_id[clazz.jvm_id] = clazz
        self.class_by_name[clazz.jvm_name] = clazz
    #

    def find_class_by_id(self, jvm_id):
        if jvm_id not in self.class_by_id:
            return None

        return self.class_by_id[jvm_id]
    #
    def find_class_by_name(self, name):
        if name not in self.class_by_name:
            return None

        return self.class_by_name[name]
