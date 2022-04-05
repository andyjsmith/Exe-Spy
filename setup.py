from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="exespy",
    version="1.0.0",
    author="Andy Smith",
    description="Cross-platform PE Viewer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/andyjsmith/ExeSpy",
    keywords=[
        "pe",
        "forensics",
        "windows forensics",
        "forensics tools"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Environment :: Win32 (MS Windows)",
        "Environment :: X11 Applications",
        "Environment :: X11 Applications :: Qt",
        "Environment :: MacOS X"
    ],
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "PySide6",
        "pefile",
        "lief",
        "humanize",
        "icoextract"
    ],
    entry_points={
        "console_scripts": ["exespy=exespy.exespy:main"],
    },
    include_package_data=True
)
