from setuptools import setup, Extension
from Cython.Build import cythonize
import os

# .py 파일을 .pyx로 복사
import shutil
shutil.copy('./email_analyzer/integration.py', './email_analyzer/integration.pyx')

# 현재 디렉토리 구조에 맞게 수정
ext_modules = [
    Extension(
        "integration",  # 모듈 이름 간단하게
        ["email_analyzer/integration.pyx"],
        extra_compile_args=['-O3'],
        extra_link_args=[]
    )
]

setup(
    name="email_analyzer",
    ext_modules = cythonize(ext_modules),
)