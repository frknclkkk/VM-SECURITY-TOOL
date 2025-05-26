from setuptools import setup, find_packages

setup(
    name="vm_security_tool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'psutil>=5.8.0',
        'netifaces'
          # For direct iptables access
    ],
    package_data={
        'vm_security_tool': [
            'remediator.py',
            'scanners/*.py',
            'utils/*.py',
            'config/*.py'
        ],
    },
    entry_points={
        'console_scripts': [
            'vm-security-scan=vm_security_tool.cli:main',
            'vm-security-unblock=vm_security_tool.remediator:unblock_cli'
        ],
    },
    data_files=[
        ('/etc/vm_security', ['config/settings.json']),
        ('/var/lib/vm_security', [])
    ],
    python_requires=">=3.6",
)
